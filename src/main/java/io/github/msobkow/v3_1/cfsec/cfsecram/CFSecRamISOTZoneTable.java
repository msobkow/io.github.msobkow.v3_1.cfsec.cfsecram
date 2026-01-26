
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
import java.time.*;
import java.util.*;
import org.apache.commons.codec.binary.Base64;
import io.github.msobkow.v3_1.cflib.*;
import io.github.msobkow.v3_1.cflib.dbutil.*;

import io.github.msobkow.v3_1.cfsec.cfsec.*;
import io.github.msobkow.v3_1.cfsec.cfsec.buff.*;
import io.github.msobkow.v3_1.cfsec.cfsecobj.*;

/*
 *	CFSecRamISOTZoneTable in-memory RAM DbIO implementation
 *	for ISOTZone.
 */
public class CFSecRamISOTZoneTable
	implements ICFSecISOTZoneTable
{
	private ICFSecSchema schema;
	private Map< Short,
				CFSecBuffISOTZone > dictByPKey
		= new HashMap< Short,
				CFSecBuffISOTZone >();
	private Map< CFSecBuffISOTZoneByOffsetIdxKey,
				Map< Short,
					CFSecBuffISOTZone >> dictByOffsetIdx
		= new HashMap< CFSecBuffISOTZoneByOffsetIdxKey,
				Map< Short,
					CFSecBuffISOTZone >>();
	private Map< CFSecBuffISOTZoneByUTZNameIdxKey,
			CFSecBuffISOTZone > dictByUTZNameIdx
		= new HashMap< CFSecBuffISOTZoneByUTZNameIdxKey,
			CFSecBuffISOTZone >();
	private Map< CFSecBuffISOTZoneByIso8601IdxKey,
				Map< Short,
					CFSecBuffISOTZone >> dictByIso8601Idx
		= new HashMap< CFSecBuffISOTZoneByIso8601IdxKey,
				Map< Short,
					CFSecBuffISOTZone >>();

	public CFSecRamISOTZoneTable( ICFSecSchema argSchema ) {
		schema = argSchema;
	}

	public void createISOTZone( ICFSecAuthorization Authorization,
		ICFSecISOTZone Buff )
	{
		final String S_ProcName = "createISOTZone";
		Short pkey = schema.getFactoryISOTZone().newPKey();
		pkey.setRequiredISOTZoneId( schema.nextISOTZoneIdGen() );
		Buff.setRequiredISOTZoneId( pkey.getRequiredISOTZoneId() );
		CFSecBuffISOTZoneByOffsetIdxKey keyOffsetIdx = schema.getFactoryISOTZone().newOffsetIdxKey();
		keyOffsetIdx.setRequiredTZHourOffset( Buff.getRequiredTZHourOffset() );
		keyOffsetIdx.setRequiredTZMinOffset( Buff.getRequiredTZMinOffset() );

		CFSecBuffISOTZoneByUTZNameIdxKey keyUTZNameIdx = schema.getFactoryISOTZone().newUTZNameIdxKey();
		keyUTZNameIdx.setRequiredTZName( Buff.getRequiredTZName() );

		CFSecBuffISOTZoneByIso8601IdxKey keyIso8601Idx = schema.getFactoryISOTZone().newIso8601IdxKey();
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

		Map< Short, CFSecBuffISOTZone > subdictOffsetIdx;
		if( dictByOffsetIdx.containsKey( keyOffsetIdx ) ) {
			subdictOffsetIdx = dictByOffsetIdx.get( keyOffsetIdx );
		}
		else {
			subdictOffsetIdx = new HashMap< Short, CFSecBuffISOTZone >();
			dictByOffsetIdx.put( keyOffsetIdx, subdictOffsetIdx );
		}
		subdictOffsetIdx.put( pkey, Buff );

		dictByUTZNameIdx.put( keyUTZNameIdx, Buff );

		Map< Short, CFSecBuffISOTZone > subdictIso8601Idx;
		if( dictByIso8601Idx.containsKey( keyIso8601Idx ) ) {
			subdictIso8601Idx = dictByIso8601Idx.get( keyIso8601Idx );
		}
		else {
			subdictIso8601Idx = new HashMap< Short, CFSecBuffISOTZone >();
			dictByIso8601Idx.put( keyIso8601Idx, subdictIso8601Idx );
		}
		subdictIso8601Idx.put( pkey, Buff );

	}

	public ICFSecISOTZone readDerived( ICFSecAuthorization Authorization,
		Short PKey )
	{
		final String S_ProcName = "CFSecRamISOTZone.readDerived";
		ICFSecISOTZone buff;
		if( dictByPKey.containsKey( PKey ) ) {
			buff = dictByPKey.get( PKey );
		}
		else {
			buff = null;
		}
		return( buff );
	}

	public ICFSecISOTZone lockDerived( ICFSecAuthorization Authorization,
		Short PKey )
	{
		final String S_ProcName = "CFSecRamISOTZone.readDerived";
		Short key = schema.getFactoryISOTZone().newPKey();
		key.setRequiredISOTZoneId( PKey.getRequiredISOTZoneId() );
		ICFSecISOTZone buff;
		if( dictByPKey.containsKey( key ) ) {
			buff = dictByPKey.get( key );
		}
		else {
			buff = null;
		}
		return( buff );
	}

	public ICFSecISOTZone[] readAllDerived( ICFSecAuthorization Authorization ) {
		final String S_ProcName = "CFSecRamISOTZone.readAllDerived";
		ICFSecISOTZone[] retList = new ICFSecISOTZone[ dictByPKey.values().size() ];
		Iterator< ICFSecISOTZone > iter = dictByPKey.values().iterator();
		int idx = 0;
		while( iter.hasNext() ) {
			retList[ idx++ ] = iter.next();
		}
		return( retList );
	}

	public ICFSecISOTZone[] readDerivedByOffsetIdx( ICFSecAuthorization Authorization,
		short TZHourOffset,
		short TZMinOffset )
	{
		final String S_ProcName = "CFSecRamISOTZone.readDerivedByOffsetIdx";
		CFSecBuffISOTZoneByOffsetIdxKey key = schema.getFactoryISOTZone().newOffsetIdxKey();
		key.setRequiredTZHourOffset( TZHourOffset );
		key.setRequiredTZMinOffset( TZMinOffset );

		ICFSecISOTZone[] recArray;
		if( dictByOffsetIdx.containsKey( key ) ) {
			Map< Short, CFSecBuffISOTZone > subdictOffsetIdx
				= dictByOffsetIdx.get( key );
			recArray = new ICFSecISOTZone[ subdictOffsetIdx.size() ];
			Iterator< ICFSecISOTZone > iter = subdictOffsetIdx.values().iterator();
			int idx = 0;
			while( iter.hasNext() ) {
				recArray[ idx++ ] = iter.next();
			}
		}
		else {
			Map< Short, CFSecBuffISOTZone > subdictOffsetIdx
				= new HashMap< Short, CFSecBuffISOTZone >();
			dictByOffsetIdx.put( key, subdictOffsetIdx );
			recArray = new ICFSecISOTZone[0];
		}
		return( recArray );
	}

	public ICFSecISOTZone readDerivedByUTZNameIdx( ICFSecAuthorization Authorization,
		String TZName )
	{
		final String S_ProcName = "CFSecRamISOTZone.readDerivedByUTZNameIdx";
		CFSecBuffISOTZoneByUTZNameIdxKey key = schema.getFactoryISOTZone().newUTZNameIdxKey();
		key.setRequiredTZName( TZName );

		ICFSecISOTZone buff;
		if( dictByUTZNameIdx.containsKey( key ) ) {
			buff = dictByUTZNameIdx.get( key );
		}
		else {
			buff = null;
		}
		return( buff );
	}

	public ICFSecISOTZone[] readDerivedByIso8601Idx( ICFSecAuthorization Authorization,
		String Iso8601 )
	{
		final String S_ProcName = "CFSecRamISOTZone.readDerivedByIso8601Idx";
		CFSecBuffISOTZoneByIso8601IdxKey key = schema.getFactoryISOTZone().newIso8601IdxKey();
		key.setRequiredIso8601( Iso8601 );

		ICFSecISOTZone[] recArray;
		if( dictByIso8601Idx.containsKey( key ) ) {
			Map< Short, CFSecBuffISOTZone > subdictIso8601Idx
				= dictByIso8601Idx.get( key );
			recArray = new ICFSecISOTZone[ subdictIso8601Idx.size() ];
			Iterator< ICFSecISOTZone > iter = subdictIso8601Idx.values().iterator();
			int idx = 0;
			while( iter.hasNext() ) {
				recArray[ idx++ ] = iter.next();
			}
		}
		else {
			Map< Short, CFSecBuffISOTZone > subdictIso8601Idx
				= new HashMap< Short, CFSecBuffISOTZone >();
			dictByIso8601Idx.put( key, subdictIso8601Idx );
			recArray = new ICFSecISOTZone[0];
		}
		return( recArray );
	}

	public ICFSecISOTZone readDerivedByIdIdx( ICFSecAuthorization Authorization,
		short ISOTZoneId )
	{
		final String S_ProcName = "CFSecRamISOTZone.readDerivedByIdIdx() ";
		Short key = schema.getFactoryISOTZone().newPKey();
		key.setRequiredISOTZoneId( ISOTZoneId );

		ICFSecISOTZone buff;
		if( dictByPKey.containsKey( key ) ) {
			buff = dictByPKey.get( key );
		}
		else {
			buff = null;
		}
		return( buff );
	}

	public ICFSecISOTZone readBuff( ICFSecAuthorization Authorization,
		Short PKey )
	{
		final String S_ProcName = "CFSecRamISOTZone.readBuff";
		ICFSecISOTZone buff = readDerived( Authorization, PKey );
		if( ( buff != null ) && ( ! buff.getClassCode().equals( "a008" ) ) ) {
			buff = null;
		}
		return( buff );
	}

	public ICFSecISOTZone lockBuff( ICFSecAuthorization Authorization,
		Short PKey )
	{
		final String S_ProcName = "lockBuff";
		ICFSecISOTZone buff = readDerived( Authorization, PKey );
		if( ( buff != null ) && ( ! buff.getClassCode().equals( "a008" ) ) ) {
			buff = null;
		}
		return( buff );
	}

	public ICFSecISOTZone[] readAllBuff( ICFSecAuthorization Authorization )
	{
		final String S_ProcName = "CFSecRamISOTZone.readAllBuff";
		ICFSecISOTZone buff;
		ArrayList<ICFSecISOTZone> filteredList = new ArrayList<ICFSecISOTZone>();
		ICFSecISOTZone[] buffList = readAllDerived( Authorization );
		for( int idx = 0; idx < buffList.length; idx ++ ) {
			buff = buffList[idx];
			if( ( buff != null ) && buff.getClassCode().equals( "a008" ) ) {
				filteredList.add( buff );
			}
		}
		return( filteredList.toArray( new ICFSecISOTZone[0] ) );
	}

	public ICFSecISOTZone readBuffByIdIdx( ICFSecAuthorization Authorization,
		short ISOTZoneId )
	{
		final String S_ProcName = "CFSecRamISOTZone.readBuffByIdIdx() ";
		ICFSecISOTZone buff = readDerivedByIdIdx( Authorization,
			ISOTZoneId );
		if( ( buff != null ) && buff.getClassCode().equals( "a008" ) ) {
			return( (ICFSecISOTZone)buff );
		}
		else {
			return( null );
		}
	}

	public ICFSecISOTZone[] readBuffByOffsetIdx( ICFSecAuthorization Authorization,
		short TZHourOffset,
		short TZMinOffset )
	{
		final String S_ProcName = "CFSecRamISOTZone.readBuffByOffsetIdx() ";
		ICFSecISOTZone buff;
		ArrayList<ICFSecISOTZone> filteredList = new ArrayList<ICFSecISOTZone>();
		ICFSecISOTZone[] buffList = readDerivedByOffsetIdx( Authorization,
			TZHourOffset,
			TZMinOffset );
		for( int idx = 0; idx < buffList.length; idx ++ ) {
			buff = buffList[idx];
			if( ( buff != null ) && buff.getClassCode().equals( "a008" ) ) {
				filteredList.add( (ICFSecISOTZone)buff );
			}
		}
		return( filteredList.toArray( new ICFSecISOTZone[0] ) );
	}

	public ICFSecISOTZone readBuffByUTZNameIdx( ICFSecAuthorization Authorization,
		String TZName )
	{
		final String S_ProcName = "CFSecRamISOTZone.readBuffByUTZNameIdx() ";
		ICFSecISOTZone buff = readDerivedByUTZNameIdx( Authorization,
			TZName );
		if( ( buff != null ) && buff.getClassCode().equals( "a008" ) ) {
			return( (ICFSecISOTZone)buff );
		}
		else {
			return( null );
		}
	}

	public ICFSecISOTZone[] readBuffByIso8601Idx( ICFSecAuthorization Authorization,
		String Iso8601 )
	{
		final String S_ProcName = "CFSecRamISOTZone.readBuffByIso8601Idx() ";
		ICFSecISOTZone buff;
		ArrayList<ICFSecISOTZone> filteredList = new ArrayList<ICFSecISOTZone>();
		ICFSecISOTZone[] buffList = readDerivedByIso8601Idx( Authorization,
			Iso8601 );
		for( int idx = 0; idx < buffList.length; idx ++ ) {
			buff = buffList[idx];
			if( ( buff != null ) && buff.getClassCode().equals( "a008" ) ) {
				filteredList.add( (ICFSecISOTZone)buff );
			}
		}
		return( filteredList.toArray( new ICFSecISOTZone[0] ) );
	}

	public void updateISOTZone( ICFSecAuthorization Authorization,
		ICFSecISOTZone Buff )
	{
		Short pkey = schema.getFactoryISOTZone().newPKey();
		pkey.setRequiredISOTZoneId( Buff.getRequiredISOTZoneId() );
		ICFSecISOTZone existing = dictByPKey.get( pkey );
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
		CFSecBuffISOTZoneByOffsetIdxKey existingKeyOffsetIdx = schema.getFactoryISOTZone().newOffsetIdxKey();
		existingKeyOffsetIdx.setRequiredTZHourOffset( existing.getRequiredTZHourOffset() );
		existingKeyOffsetIdx.setRequiredTZMinOffset( existing.getRequiredTZMinOffset() );

		CFSecBuffISOTZoneByOffsetIdxKey newKeyOffsetIdx = schema.getFactoryISOTZone().newOffsetIdxKey();
		newKeyOffsetIdx.setRequiredTZHourOffset( Buff.getRequiredTZHourOffset() );
		newKeyOffsetIdx.setRequiredTZMinOffset( Buff.getRequiredTZMinOffset() );

		CFSecBuffISOTZoneByUTZNameIdxKey existingKeyUTZNameIdx = schema.getFactoryISOTZone().newUTZNameIdxKey();
		existingKeyUTZNameIdx.setRequiredTZName( existing.getRequiredTZName() );

		CFSecBuffISOTZoneByUTZNameIdxKey newKeyUTZNameIdx = schema.getFactoryISOTZone().newUTZNameIdxKey();
		newKeyUTZNameIdx.setRequiredTZName( Buff.getRequiredTZName() );

		CFSecBuffISOTZoneByIso8601IdxKey existingKeyIso8601Idx = schema.getFactoryISOTZone().newIso8601IdxKey();
		existingKeyIso8601Idx.setRequiredIso8601( existing.getRequiredIso8601() );

		CFSecBuffISOTZoneByIso8601IdxKey newKeyIso8601Idx = schema.getFactoryISOTZone().newIso8601IdxKey();
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

		Map< Short, CFSecBuffISOTZone > subdict;

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
			subdict = new HashMap< Short, CFSecBuffISOTZone >();
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
			subdict = new HashMap< Short, CFSecBuffISOTZone >();
			dictByIso8601Idx.put( newKeyIso8601Idx, subdict );
		}
		subdict.put( pkey, Buff );

	}

	public void deleteISOTZone( ICFSecAuthorization Authorization,
		ICFSecISOTZone Buff )
	{
		final String S_ProcName = "CFSecRamISOTZoneTable.deleteISOTZone() ";
		String classCode;
		Short pkey = schema.getFactoryISOTZone().newPKey();
		pkey.setRequiredISOTZoneId( Buff.getRequiredISOTZoneId() );
		ICFSecISOTZone existing = dictByPKey.get( pkey );
		if( existing == null ) {
			return;
		}
		if( existing.getRequiredRevision() != Buff.getRequiredRevision() )
		{
			throw new CFLibCollisionDetectedException( getClass(),
				"deleteISOTZone",
				pkey );
		}
		CFSecBuffISOTZoneByOffsetIdxKey keyOffsetIdx = schema.getFactoryISOTZone().newOffsetIdxKey();
		keyOffsetIdx.setRequiredTZHourOffset( existing.getRequiredTZHourOffset() );
		keyOffsetIdx.setRequiredTZMinOffset( existing.getRequiredTZMinOffset() );

		CFSecBuffISOTZoneByUTZNameIdxKey keyUTZNameIdx = schema.getFactoryISOTZone().newUTZNameIdxKey();
		keyUTZNameIdx.setRequiredTZName( existing.getRequiredTZName() );

		CFSecBuffISOTZoneByIso8601IdxKey keyIso8601Idx = schema.getFactoryISOTZone().newIso8601IdxKey();
		keyIso8601Idx.setRequiredIso8601( existing.getRequiredIso8601() );

		// Validate reverse foreign keys

		// Delete is valid
		Map< Short, CFSecBuffISOTZone > subdict;

		dictByPKey.remove( pkey );

		subdict = dictByOffsetIdx.get( keyOffsetIdx );
		subdict.remove( pkey );

		dictByUTZNameIdx.remove( keyUTZNameIdx );

		subdict = dictByIso8601Idx.get( keyIso8601Idx );
		subdict.remove( pkey );

	}
	public void deleteISOTZoneByIdIdx( ICFSecAuthorization Authorization,
		short argISOTZoneId )
	{
		Short key = schema.getFactoryISOTZone().newPKey();
		key.setRequiredISOTZoneId( argISOTZoneId );
		deleteISOTZoneByIdIdx( Authorization, key );
	}

	public void deleteISOTZoneByIdIdx( ICFSecAuthorization Authorization,
		Short argKey )
	{
		boolean anyNotNull = false;
		anyNotNull = true;
		if( ! anyNotNull ) {
			return;
		}
		ICFSecISOTZone cur;
		LinkedList<ICFSecISOTZone> matchSet = new LinkedList<ICFSecISOTZone>();
		Iterator<ICFSecISOTZone> values = dictByPKey.values().iterator();
		while( values.hasNext() ) {
			cur = values.next();
			if( argKey.equals( cur ) ) {
				matchSet.add( cur );
			}
		}
		Iterator<ICFSecISOTZone> iterMatch = matchSet.iterator();
		while( iterMatch.hasNext() ) {
			cur = iterMatch.next();
			cur = schema.getTableISOTZone().readDerivedByIdIdx( Authorization,
				cur.getRequiredISOTZoneId() );
			deleteISOTZone( Authorization, cur );
		}
	}

	public void deleteISOTZoneByOffsetIdx( ICFSecAuthorization Authorization,
		short argTZHourOffset,
		short argTZMinOffset )
	{
		CFSecBuffISOTZoneByOffsetIdxKey key = schema.getFactoryISOTZone().newOffsetIdxKey();
		key.setRequiredTZHourOffset( argTZHourOffset );
		key.setRequiredTZMinOffset( argTZMinOffset );
		deleteISOTZoneByOffsetIdx( Authorization, key );
	}

	public void deleteISOTZoneByOffsetIdx( ICFSecAuthorization Authorization,
		ICFSecISOTZoneByOffsetIdxKey argKey )
	{
		ICFSecISOTZone cur;
		boolean anyNotNull = false;
		anyNotNull = true;
		anyNotNull = true;
		if( ! anyNotNull ) {
			return;
		}
		LinkedList<ICFSecISOTZone> matchSet = new LinkedList<ICFSecISOTZone>();
		Iterator<ICFSecISOTZone> values = dictByPKey.values().iterator();
		while( values.hasNext() ) {
			cur = values.next();
			if( argKey.equals( cur ) ) {
				matchSet.add( cur );
			}
		}
		Iterator<ICFSecISOTZone> iterMatch = matchSet.iterator();
		while( iterMatch.hasNext() ) {
			cur = iterMatch.next();
			cur = schema.getTableISOTZone().readDerivedByIdIdx( Authorization,
				cur.getRequiredISOTZoneId() );
			deleteISOTZone( Authorization, cur );
		}
	}

	public void deleteISOTZoneByUTZNameIdx( ICFSecAuthorization Authorization,
		String argTZName )
	{
		CFSecBuffISOTZoneByUTZNameIdxKey key = schema.getFactoryISOTZone().newUTZNameIdxKey();
		key.setRequiredTZName( argTZName );
		deleteISOTZoneByUTZNameIdx( Authorization, key );
	}

	public void deleteISOTZoneByUTZNameIdx( ICFSecAuthorization Authorization,
		ICFSecISOTZoneByUTZNameIdxKey argKey )
	{
		ICFSecISOTZone cur;
		boolean anyNotNull = false;
		anyNotNull = true;
		if( ! anyNotNull ) {
			return;
		}
		LinkedList<ICFSecISOTZone> matchSet = new LinkedList<ICFSecISOTZone>();
		Iterator<ICFSecISOTZone> values = dictByPKey.values().iterator();
		while( values.hasNext() ) {
			cur = values.next();
			if( argKey.equals( cur ) ) {
				matchSet.add( cur );
			}
		}
		Iterator<ICFSecISOTZone> iterMatch = matchSet.iterator();
		while( iterMatch.hasNext() ) {
			cur = iterMatch.next();
			cur = schema.getTableISOTZone().readDerivedByIdIdx( Authorization,
				cur.getRequiredISOTZoneId() );
			deleteISOTZone( Authorization, cur );
		}
	}

	public void deleteISOTZoneByIso8601Idx( ICFSecAuthorization Authorization,
		String argIso8601 )
	{
		CFSecBuffISOTZoneByIso8601IdxKey key = schema.getFactoryISOTZone().newIso8601IdxKey();
		key.setRequiredIso8601( argIso8601 );
		deleteISOTZoneByIso8601Idx( Authorization, key );
	}

	public void deleteISOTZoneByIso8601Idx( ICFSecAuthorization Authorization,
		ICFSecISOTZoneByIso8601IdxKey argKey )
	{
		ICFSecISOTZone cur;
		boolean anyNotNull = false;
		anyNotNull = true;
		if( ! anyNotNull ) {
			return;
		}
		LinkedList<ICFSecISOTZone> matchSet = new LinkedList<ICFSecISOTZone>();
		Iterator<ICFSecISOTZone> values = dictByPKey.values().iterator();
		while( values.hasNext() ) {
			cur = values.next();
			if( argKey.equals( cur ) ) {
				matchSet.add( cur );
			}
		}
		Iterator<ICFSecISOTZone> iterMatch = matchSet.iterator();
		while( iterMatch.hasNext() ) {
			cur = iterMatch.next();
			cur = schema.getTableISOTZone().readDerivedByIdIdx( Authorization,
				cur.getRequiredISOTZoneId() );
			deleteISOTZone( Authorization, cur );
		}
	}
}
