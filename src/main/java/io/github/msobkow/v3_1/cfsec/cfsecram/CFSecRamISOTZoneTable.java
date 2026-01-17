
// Description: Java 25 in-memory RAM DbIO implementation for ISOTZone.

/*
 *	io.github.msobkow.CFSec
 *
 *	Copyright (c) 2016-2026 Mark Stephen Sobkow
 *	
 *	Mark's Code Fractal 3.1 CFSec - Security Services
 *	
 *	This file is part of Mark's Code Fractal CFSec.
 *	
 *	Mark's Code Fractal CFSec is available under dual commercial license from
 *	Mark Stephen Sobkow, or under the terms of the GNU Library General Public License,
 *	Version 3 or later.
 *	
 *	Mark's Code Fractal CFSec is free software: you can redistribute it and/or
 *	modify it under the terms of the GNU Library General Public License as published by
 *	the Free Software Foundation, either version 3 of the License, or
 *	(at your option) any later version.
 *	
 *	Mark's Code Fractal CFSec is distributed in the hope that it will be useful,
 *	but WITHOUT ANY WARRANTY; without even the implied warranty of
 *	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *	GNU General Public License for more details.
 *	
 *	You should have received a copy of the GNU Library General Public License
 *	along with Mark's Code Fractal CFSec.  If not, see <https://www.gnu.org/licenses/>.
 *	
 *	If you wish to modify and use this code without publishing your changes in order to
 *	tie it to proprietary code, please contact Mark Stephen Sobkow
 *	for a commercial license at mark.sobkow@gmail.com
 *	
 */

package io.github.msobkow.v3_1.cfsec.cfsecram;

import java.math.*;
import java.sql.*;
import java.text.*;
import java.util.*;
import org.apache.commons.codec.binary.Base64;
import io.github.msobkow.v3_1.cflib.*;
import io.github.msobkow.v3_1.cflib.dbutil.*;

import io.github.msobkow.v3_1.cfsec.cfsec.*;
import io.github.msobkow.v3_1.cfsec.cfsecobj.*;
import io.github.msobkow.v3_1.cfsec.cfsecobj.*;

/*
 *	CFSecRamISOTZoneTable in-memory RAM DbIO implementation
 *	for ISOTZone.
 */
public class CFSecRamISOTZoneTable
	implements ICFSecISOTZoneTable
{
	private ICFSecSchema schema;
	private Map< CFSecISOTZonePKey,
				CFSecISOTZoneBuff > dictByPKey
		= new HashMap< CFSecISOTZonePKey,
				CFSecISOTZoneBuff >();
	private Map< CFSecISOTZoneByOffsetIdxKey,
				Map< CFSecISOTZonePKey,
					CFSecISOTZoneBuff >> dictByOffsetIdx
		= new HashMap< CFSecISOTZoneByOffsetIdxKey,
				Map< CFSecISOTZonePKey,
					CFSecISOTZoneBuff >>();
	private Map< CFSecISOTZoneByUTZNameIdxKey,
			CFSecISOTZoneBuff > dictByUTZNameIdx
		= new HashMap< CFSecISOTZoneByUTZNameIdxKey,
			CFSecISOTZoneBuff >();
	private Map< CFSecISOTZoneByIso8601IdxKey,
				Map< CFSecISOTZonePKey,
					CFSecISOTZoneBuff >> dictByIso8601Idx
		= new HashMap< CFSecISOTZoneByIso8601IdxKey,
				Map< CFSecISOTZonePKey,
					CFSecISOTZoneBuff >>();

	public CFSecRamISOTZoneTable( ICFSecSchema argSchema ) {
		schema = argSchema;
	}

	public void createISOTZone( CFSecAuthorization Authorization,
		CFSecISOTZoneBuff Buff )
	{
		final String S_ProcName = "createISOTZone";
		CFSecISOTZonePKey pkey = schema.getFactoryISOTZone().newPKey();
		pkey.setRequiredISOTZoneId( schema.nextISOTZoneIdGen() );
		Buff.setRequiredISOTZoneId( pkey.getRequiredISOTZoneId() );
		CFSecISOTZoneByOffsetIdxKey keyOffsetIdx = schema.getFactoryISOTZone().newOffsetIdxKey();
		keyOffsetIdx.setRequiredTZHourOffset( Buff.getRequiredTZHourOffset() );
		keyOffsetIdx.setRequiredTZMinOffset( Buff.getRequiredTZMinOffset() );

		CFSecISOTZoneByUTZNameIdxKey keyUTZNameIdx = schema.getFactoryISOTZone().newUTZNameIdxKey();
		keyUTZNameIdx.setRequiredTZName( Buff.getRequiredTZName() );

		CFSecISOTZoneByIso8601IdxKey keyIso8601Idx = schema.getFactoryISOTZone().newIso8601IdxKey();
		keyIso8601Idx.setRequiredIso8601( Buff.getRequiredIso8601() );

		// Validate unique indexes

		if( dictByPKey.containsKey( pkey ) ) {
			throw new CFLibPrimaryKeyNotNewException( getClass(), S_ProcName, pkey );
		}

		if( dictByUTZNameIdx.containsKey( keyUTZNameIdx ) ) {
			throw new CFLibUniqueIndexViolationException( getClass(),
				S_ProcName,
				"ISOTZoneUTZNameIdx",
				keyUTZNameIdx );
		}

		// Validate foreign keys

		// Proceed with adding the new record

		dictByPKey.put( pkey, Buff );

		Map< CFSecISOTZonePKey, CFSecISOTZoneBuff > subdictOffsetIdx;
		if( dictByOffsetIdx.containsKey( keyOffsetIdx ) ) {
			subdictOffsetIdx = dictByOffsetIdx.get( keyOffsetIdx );
		}
		else {
			subdictOffsetIdx = new HashMap< CFSecISOTZonePKey, CFSecISOTZoneBuff >();
			dictByOffsetIdx.put( keyOffsetIdx, subdictOffsetIdx );
		}
		subdictOffsetIdx.put( pkey, Buff );

		dictByUTZNameIdx.put( keyUTZNameIdx, Buff );

		Map< CFSecISOTZonePKey, CFSecISOTZoneBuff > subdictIso8601Idx;
		if( dictByIso8601Idx.containsKey( keyIso8601Idx ) ) {
			subdictIso8601Idx = dictByIso8601Idx.get( keyIso8601Idx );
		}
		else {
			subdictIso8601Idx = new HashMap< CFSecISOTZonePKey, CFSecISOTZoneBuff >();
			dictByIso8601Idx.put( keyIso8601Idx, subdictIso8601Idx );
		}
		subdictIso8601Idx.put( pkey, Buff );

	}

	public CFSecISOTZoneBuff readDerived( CFSecAuthorization Authorization,
		CFSecISOTZonePKey PKey )
	{
		final String S_ProcName = "CFSecRamISOTZone.readDerived";
		CFSecISOTZonePKey key = schema.getFactoryISOTZone().newPKey();
		key.setRequiredISOTZoneId( PKey.getRequiredISOTZoneId() );
		CFSecISOTZoneBuff buff;
		if( dictByPKey.containsKey( key ) ) {
			buff = dictByPKey.get( key );
		}
		else {
			buff = null;
		}
		return( buff );
	}

	public CFSecISOTZoneBuff lockDerived( CFSecAuthorization Authorization,
		CFSecISOTZonePKey PKey )
	{
		final String S_ProcName = "CFSecRamISOTZone.readDerived";
		CFSecISOTZonePKey key = schema.getFactoryISOTZone().newPKey();
		key.setRequiredISOTZoneId( PKey.getRequiredISOTZoneId() );
		CFSecISOTZoneBuff buff;
		if( dictByPKey.containsKey( key ) ) {
			buff = dictByPKey.get( key );
		}
		else {
			buff = null;
		}
		return( buff );
	}

	public CFSecISOTZoneBuff[] readAllDerived( CFSecAuthorization Authorization ) {
		final String S_ProcName = "CFSecRamISOTZone.readAllDerived";
		CFSecISOTZoneBuff[] retList = new CFSecISOTZoneBuff[ dictByPKey.values().size() ];
		Iterator< CFSecISOTZoneBuff > iter = dictByPKey.values().iterator();
		int idx = 0;
		while( iter.hasNext() ) {
			retList[ idx++ ] = iter.next();
		}
		return( retList );
	}

	public CFSecISOTZoneBuff[] readDerivedByOffsetIdx( CFSecAuthorization Authorization,
		short TZHourOffset,
		short TZMinOffset )
	{
		final String S_ProcName = "CFSecRamISOTZone.readDerivedByOffsetIdx";
		CFSecISOTZoneByOffsetIdxKey key = schema.getFactoryISOTZone().newOffsetIdxKey();
		key.setRequiredTZHourOffset( TZHourOffset );
		key.setRequiredTZMinOffset( TZMinOffset );

		CFSecISOTZoneBuff[] recArray;
		if( dictByOffsetIdx.containsKey( key ) ) {
			Map< CFSecISOTZonePKey, CFSecISOTZoneBuff > subdictOffsetIdx
				= dictByOffsetIdx.get( key );
			recArray = new CFSecISOTZoneBuff[ subdictOffsetIdx.size() ];
			Iterator< CFSecISOTZoneBuff > iter = subdictOffsetIdx.values().iterator();
			int idx = 0;
			while( iter.hasNext() ) {
				recArray[ idx++ ] = iter.next();
			}
		}
		else {
			Map< CFSecISOTZonePKey, CFSecISOTZoneBuff > subdictOffsetIdx
				= new HashMap< CFSecISOTZonePKey, CFSecISOTZoneBuff >();
			dictByOffsetIdx.put( key, subdictOffsetIdx );
			recArray = new CFSecISOTZoneBuff[0];
		}
		return( recArray );
	}

	public CFSecISOTZoneBuff readDerivedByUTZNameIdx( CFSecAuthorization Authorization,
		String TZName )
	{
		final String S_ProcName = "CFSecRamISOTZone.readDerivedByUTZNameIdx";
		CFSecISOTZoneByUTZNameIdxKey key = schema.getFactoryISOTZone().newUTZNameIdxKey();
		key.setRequiredTZName( TZName );

		CFSecISOTZoneBuff buff;
		if( dictByUTZNameIdx.containsKey( key ) ) {
			buff = dictByUTZNameIdx.get( key );
		}
		else {
			buff = null;
		}
		return( buff );
	}

	public CFSecISOTZoneBuff[] readDerivedByIso8601Idx( CFSecAuthorization Authorization,
		String Iso8601 )
	{
		final String S_ProcName = "CFSecRamISOTZone.readDerivedByIso8601Idx";
		CFSecISOTZoneByIso8601IdxKey key = schema.getFactoryISOTZone().newIso8601IdxKey();
		key.setRequiredIso8601( Iso8601 );

		CFSecISOTZoneBuff[] recArray;
		if( dictByIso8601Idx.containsKey( key ) ) {
			Map< CFSecISOTZonePKey, CFSecISOTZoneBuff > subdictIso8601Idx
				= dictByIso8601Idx.get( key );
			recArray = new CFSecISOTZoneBuff[ subdictIso8601Idx.size() ];
			Iterator< CFSecISOTZoneBuff > iter = subdictIso8601Idx.values().iterator();
			int idx = 0;
			while( iter.hasNext() ) {
				recArray[ idx++ ] = iter.next();
			}
		}
		else {
			Map< CFSecISOTZonePKey, CFSecISOTZoneBuff > subdictIso8601Idx
				= new HashMap< CFSecISOTZonePKey, CFSecISOTZoneBuff >();
			dictByIso8601Idx.put( key, subdictIso8601Idx );
			recArray = new CFSecISOTZoneBuff[0];
		}
		return( recArray );
	}

	public CFSecISOTZoneBuff readDerivedByIdIdx( CFSecAuthorization Authorization,
		short ISOTZoneId )
	{
		final String S_ProcName = "CFSecRamISOTZone.readDerivedByIdIdx() ";
		CFSecISOTZonePKey key = schema.getFactoryISOTZone().newPKey();
		key.setRequiredISOTZoneId( ISOTZoneId );

		CFSecISOTZoneBuff buff;
		if( dictByPKey.containsKey( key ) ) {
			buff = dictByPKey.get( key );
		}
		else {
			buff = null;
		}
		return( buff );
	}

	public CFSecISOTZoneBuff readBuff( CFSecAuthorization Authorization,
		CFSecISOTZonePKey PKey )
	{
		final String S_ProcName = "CFSecRamISOTZone.readBuff";
		CFSecISOTZoneBuff buff = readDerived( Authorization, PKey );
		if( ( buff != null ) && ( ! buff.getClassCode().equals( "a008" ) ) ) {
			buff = null;
		}
		return( buff );
	}

	public CFSecISOTZoneBuff lockBuff( CFSecAuthorization Authorization,
		CFSecISOTZonePKey PKey )
	{
		final String S_ProcName = "lockBuff";
		CFSecISOTZoneBuff buff = readDerived( Authorization, PKey );
		if( ( buff != null ) && ( ! buff.getClassCode().equals( "a008" ) ) ) {
			buff = null;
		}
		return( buff );
	}

	public CFSecISOTZoneBuff[] readAllBuff( CFSecAuthorization Authorization )
	{
		final String S_ProcName = "CFSecRamISOTZone.readAllBuff";
		CFSecISOTZoneBuff buff;
		ArrayList<CFSecISOTZoneBuff> filteredList = new ArrayList<CFSecISOTZoneBuff>();
		CFSecISOTZoneBuff[] buffList = readAllDerived( Authorization );
		for( int idx = 0; idx < buffList.length; idx ++ ) {
			buff = buffList[idx];
			if( ( buff != null ) && buff.getClassCode().equals( "a008" ) ) {
				filteredList.add( buff );
			}
		}
		return( filteredList.toArray( new CFSecISOTZoneBuff[0] ) );
	}

	public CFSecISOTZoneBuff readBuffByIdIdx( CFSecAuthorization Authorization,
		short ISOTZoneId )
	{
		final String S_ProcName = "CFSecRamISOTZone.readBuffByIdIdx() ";
		CFSecISOTZoneBuff buff = readDerivedByIdIdx( Authorization,
			ISOTZoneId );
		if( ( buff != null ) && buff.getClassCode().equals( "a008" ) ) {
			return( (CFSecISOTZoneBuff)buff );
		}
		else {
			return( null );
		}
	}

	public CFSecISOTZoneBuff[] readBuffByOffsetIdx( CFSecAuthorization Authorization,
		short TZHourOffset,
		short TZMinOffset )
	{
		final String S_ProcName = "CFSecRamISOTZone.readBuffByOffsetIdx() ";
		CFSecISOTZoneBuff buff;
		ArrayList<CFSecISOTZoneBuff> filteredList = new ArrayList<CFSecISOTZoneBuff>();
		CFSecISOTZoneBuff[] buffList = readDerivedByOffsetIdx( Authorization,
			TZHourOffset,
			TZMinOffset );
		for( int idx = 0; idx < buffList.length; idx ++ ) {
			buff = buffList[idx];
			if( ( buff != null ) && buff.getClassCode().equals( "a008" ) ) {
				filteredList.add( (CFSecISOTZoneBuff)buff );
			}
		}
		return( filteredList.toArray( new CFSecISOTZoneBuff[0] ) );
	}

	public CFSecISOTZoneBuff readBuffByUTZNameIdx( CFSecAuthorization Authorization,
		String TZName )
	{
		final String S_ProcName = "CFSecRamISOTZone.readBuffByUTZNameIdx() ";
		CFSecISOTZoneBuff buff = readDerivedByUTZNameIdx( Authorization,
			TZName );
		if( ( buff != null ) && buff.getClassCode().equals( "a008" ) ) {
			return( (CFSecISOTZoneBuff)buff );
		}
		else {
			return( null );
		}
	}

	public CFSecISOTZoneBuff[] readBuffByIso8601Idx( CFSecAuthorization Authorization,
		String Iso8601 )
	{
		final String S_ProcName = "CFSecRamISOTZone.readBuffByIso8601Idx() ";
		CFSecISOTZoneBuff buff;
		ArrayList<CFSecISOTZoneBuff> filteredList = new ArrayList<CFSecISOTZoneBuff>();
		CFSecISOTZoneBuff[] buffList = readDerivedByIso8601Idx( Authorization,
			Iso8601 );
		for( int idx = 0; idx < buffList.length; idx ++ ) {
			buff = buffList[idx];
			if( ( buff != null ) && buff.getClassCode().equals( "a008" ) ) {
				filteredList.add( (CFSecISOTZoneBuff)buff );
			}
		}
		return( filteredList.toArray( new CFSecISOTZoneBuff[0] ) );
	}

	public void updateISOTZone( CFSecAuthorization Authorization,
		CFSecISOTZoneBuff Buff )
	{
		CFSecISOTZonePKey pkey = schema.getFactoryISOTZone().newPKey();
		pkey.setRequiredISOTZoneId( Buff.getRequiredISOTZoneId() );
		CFSecISOTZoneBuff existing = dictByPKey.get( pkey );
		if( existing == null ) {
			throw new CFLibStaleCacheDetectedException( getClass(),
				"updateISOTZone",
				"Existing record not found",
				"ISOTZone",
				pkey );
		}
		if( existing.getRequiredRevision() != Buff.getRequiredRevision() ) {
			throw new CFLibCollisionDetectedException( getClass(),
				"updateISOTZone",
				pkey );
		}
		Buff.setRequiredRevision( Buff.getRequiredRevision() + 1 );
		CFSecISOTZoneByOffsetIdxKey existingKeyOffsetIdx = schema.getFactoryISOTZone().newOffsetIdxKey();
		existingKeyOffsetIdx.setRequiredTZHourOffset( existing.getRequiredTZHourOffset() );
		existingKeyOffsetIdx.setRequiredTZMinOffset( existing.getRequiredTZMinOffset() );

		CFSecISOTZoneByOffsetIdxKey newKeyOffsetIdx = schema.getFactoryISOTZone().newOffsetIdxKey();
		newKeyOffsetIdx.setRequiredTZHourOffset( Buff.getRequiredTZHourOffset() );
		newKeyOffsetIdx.setRequiredTZMinOffset( Buff.getRequiredTZMinOffset() );

		CFSecISOTZoneByUTZNameIdxKey existingKeyUTZNameIdx = schema.getFactoryISOTZone().newUTZNameIdxKey();
		existingKeyUTZNameIdx.setRequiredTZName( existing.getRequiredTZName() );

		CFSecISOTZoneByUTZNameIdxKey newKeyUTZNameIdx = schema.getFactoryISOTZone().newUTZNameIdxKey();
		newKeyUTZNameIdx.setRequiredTZName( Buff.getRequiredTZName() );

		CFSecISOTZoneByIso8601IdxKey existingKeyIso8601Idx = schema.getFactoryISOTZone().newIso8601IdxKey();
		existingKeyIso8601Idx.setRequiredIso8601( existing.getRequiredIso8601() );

		CFSecISOTZoneByIso8601IdxKey newKeyIso8601Idx = schema.getFactoryISOTZone().newIso8601IdxKey();
		newKeyIso8601Idx.setRequiredIso8601( Buff.getRequiredIso8601() );

		// Check unique indexes

		if( ! existingKeyUTZNameIdx.equals( newKeyUTZNameIdx ) ) {
			if( dictByUTZNameIdx.containsKey( newKeyUTZNameIdx ) ) {
				throw new CFLibUniqueIndexViolationException( getClass(),
					"updateISOTZone",
					"ISOTZoneUTZNameIdx",
					newKeyUTZNameIdx );
			}
		}

		// Validate foreign keys

		// Update is valid

		Map< CFSecISOTZonePKey, CFSecISOTZoneBuff > subdict;

		dictByPKey.remove( pkey );
		dictByPKey.put( pkey, Buff );

		subdict = dictByOffsetIdx.get( existingKeyOffsetIdx );
		if( subdict != null ) {
			subdict.remove( pkey );
		}
		if( dictByOffsetIdx.containsKey( newKeyOffsetIdx ) ) {
			subdict = dictByOffsetIdx.get( newKeyOffsetIdx );
		}
		else {
			subdict = new HashMap< CFSecISOTZonePKey, CFSecISOTZoneBuff >();
			dictByOffsetIdx.put( newKeyOffsetIdx, subdict );
		}
		subdict.put( pkey, Buff );

		dictByUTZNameIdx.remove( existingKeyUTZNameIdx );
		dictByUTZNameIdx.put( newKeyUTZNameIdx, Buff );

		subdict = dictByIso8601Idx.get( existingKeyIso8601Idx );
		if( subdict != null ) {
			subdict.remove( pkey );
		}
		if( dictByIso8601Idx.containsKey( newKeyIso8601Idx ) ) {
			subdict = dictByIso8601Idx.get( newKeyIso8601Idx );
		}
		else {
			subdict = new HashMap< CFSecISOTZonePKey, CFSecISOTZoneBuff >();
			dictByIso8601Idx.put( newKeyIso8601Idx, subdict );
		}
		subdict.put( pkey, Buff );

	}

	public void deleteISOTZone( CFSecAuthorization Authorization,
		CFSecISOTZoneBuff Buff )
	{
		final String S_ProcName = "CFSecRamISOTZoneTable.deleteISOTZone() ";
		String classCode;
		CFSecISOTZonePKey pkey = schema.getFactoryISOTZone().newPKey();
		pkey.setRequiredISOTZoneId( Buff.getRequiredISOTZoneId() );
		CFSecISOTZoneBuff existing = dictByPKey.get( pkey );
		if( existing == null ) {
			return;
		}
		if( existing.getRequiredRevision() != Buff.getRequiredRevision() )
		{
			throw new CFLibCollisionDetectedException( getClass(),
				"deleteISOTZone",
				pkey );
		}
		CFSecISOTZoneByOffsetIdxKey keyOffsetIdx = schema.getFactoryISOTZone().newOffsetIdxKey();
		keyOffsetIdx.setRequiredTZHourOffset( existing.getRequiredTZHourOffset() );
		keyOffsetIdx.setRequiredTZMinOffset( existing.getRequiredTZMinOffset() );

		CFSecISOTZoneByUTZNameIdxKey keyUTZNameIdx = schema.getFactoryISOTZone().newUTZNameIdxKey();
		keyUTZNameIdx.setRequiredTZName( existing.getRequiredTZName() );

		CFSecISOTZoneByIso8601IdxKey keyIso8601Idx = schema.getFactoryISOTZone().newIso8601IdxKey();
		keyIso8601Idx.setRequiredIso8601( existing.getRequiredIso8601() );

		// Validate reverse foreign keys

		// Delete is valid
		Map< CFSecISOTZonePKey, CFSecISOTZoneBuff > subdict;

		dictByPKey.remove( pkey );

		subdict = dictByOffsetIdx.get( keyOffsetIdx );
		subdict.remove( pkey );

		dictByUTZNameIdx.remove( keyUTZNameIdx );

		subdict = dictByIso8601Idx.get( keyIso8601Idx );
		subdict.remove( pkey );

	}
	public void deleteISOTZoneByIdIdx( CFSecAuthorization Authorization,
		short argISOTZoneId )
	{
		CFSecISOTZonePKey key = schema.getFactoryISOTZone().newPKey();
		key.setRequiredISOTZoneId( argISOTZoneId );
		deleteISOTZoneByIdIdx( Authorization, key );
	}

	public void deleteISOTZoneByIdIdx( CFSecAuthorization Authorization,
		CFSecISOTZonePKey argKey )
	{
		boolean anyNotNull = false;
		anyNotNull = true;
		if( ! anyNotNull ) {
			return;
		}
		CFSecISOTZoneBuff cur;
		LinkedList<CFSecISOTZoneBuff> matchSet = new LinkedList<CFSecISOTZoneBuff>();
		Iterator<CFSecISOTZoneBuff> values = dictByPKey.values().iterator();
		while( values.hasNext() ) {
			cur = values.next();
			if( argKey.equals( cur ) ) {
				matchSet.add( cur );
			}
		}
		Iterator<CFSecISOTZoneBuff> iterMatch = matchSet.iterator();
		while( iterMatch.hasNext() ) {
			cur = iterMatch.next();
			cur = schema.getTableISOTZone().readDerivedByIdIdx( Authorization,
				cur.getRequiredISOTZoneId() );
			deleteISOTZone( Authorization, cur );
		}
	}

	public void deleteISOTZoneByOffsetIdx( CFSecAuthorization Authorization,
		short argTZHourOffset,
		short argTZMinOffset )
	{
		CFSecISOTZoneByOffsetIdxKey key = schema.getFactoryISOTZone().newOffsetIdxKey();
		key.setRequiredTZHourOffset( argTZHourOffset );
		key.setRequiredTZMinOffset( argTZMinOffset );
		deleteISOTZoneByOffsetIdx( Authorization, key );
	}

	public void deleteISOTZoneByOffsetIdx( CFSecAuthorization Authorization,
		CFSecISOTZoneByOffsetIdxKey argKey )
	{
		CFSecISOTZoneBuff cur;
		boolean anyNotNull = false;
		anyNotNull = true;
		anyNotNull = true;
		if( ! anyNotNull ) {
			return;
		}
		LinkedList<CFSecISOTZoneBuff> matchSet = new LinkedList<CFSecISOTZoneBuff>();
		Iterator<CFSecISOTZoneBuff> values = dictByPKey.values().iterator();
		while( values.hasNext() ) {
			cur = values.next();
			if( argKey.equals( cur ) ) {
				matchSet.add( cur );
			}
		}
		Iterator<CFSecISOTZoneBuff> iterMatch = matchSet.iterator();
		while( iterMatch.hasNext() ) {
			cur = iterMatch.next();
			cur = schema.getTableISOTZone().readDerivedByIdIdx( Authorization,
				cur.getRequiredISOTZoneId() );
			deleteISOTZone( Authorization, cur );
		}
	}

	public void deleteISOTZoneByUTZNameIdx( CFSecAuthorization Authorization,
		String argTZName )
	{
		CFSecISOTZoneByUTZNameIdxKey key = schema.getFactoryISOTZone().newUTZNameIdxKey();
		key.setRequiredTZName( argTZName );
		deleteISOTZoneByUTZNameIdx( Authorization, key );
	}

	public void deleteISOTZoneByUTZNameIdx( CFSecAuthorization Authorization,
		CFSecISOTZoneByUTZNameIdxKey argKey )
	{
		CFSecISOTZoneBuff cur;
		boolean anyNotNull = false;
		anyNotNull = true;
		if( ! anyNotNull ) {
			return;
		}
		LinkedList<CFSecISOTZoneBuff> matchSet = new LinkedList<CFSecISOTZoneBuff>();
		Iterator<CFSecISOTZoneBuff> values = dictByPKey.values().iterator();
		while( values.hasNext() ) {
			cur = values.next();
			if( argKey.equals( cur ) ) {
				matchSet.add( cur );
			}
		}
		Iterator<CFSecISOTZoneBuff> iterMatch = matchSet.iterator();
		while( iterMatch.hasNext() ) {
			cur = iterMatch.next();
			cur = schema.getTableISOTZone().readDerivedByIdIdx( Authorization,
				cur.getRequiredISOTZoneId() );
			deleteISOTZone( Authorization, cur );
		}
	}

	public void deleteISOTZoneByIso8601Idx( CFSecAuthorization Authorization,
		String argIso8601 )
	{
		CFSecISOTZoneByIso8601IdxKey key = schema.getFactoryISOTZone().newIso8601IdxKey();
		key.setRequiredIso8601( argIso8601 );
		deleteISOTZoneByIso8601Idx( Authorization, key );
	}

	public void deleteISOTZoneByIso8601Idx( CFSecAuthorization Authorization,
		CFSecISOTZoneByIso8601IdxKey argKey )
	{
		CFSecISOTZoneBuff cur;
		boolean anyNotNull = false;
		anyNotNull = true;
		if( ! anyNotNull ) {
			return;
		}
		LinkedList<CFSecISOTZoneBuff> matchSet = new LinkedList<CFSecISOTZoneBuff>();
		Iterator<CFSecISOTZoneBuff> values = dictByPKey.values().iterator();
		while( values.hasNext() ) {
			cur = values.next();
			if( argKey.equals( cur ) ) {
				matchSet.add( cur );
			}
		}
		Iterator<CFSecISOTZoneBuff> iterMatch = matchSet.iterator();
		while( iterMatch.hasNext() ) {
			cur = iterMatch.next();
			cur = schema.getTableISOTZone().readDerivedByIdIdx( Authorization,
				cur.getRequiredISOTZoneId() );
			deleteISOTZone( Authorization, cur );
		}
	}
}
