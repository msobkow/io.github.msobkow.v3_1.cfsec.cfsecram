
// Description: Java 25 in-memory RAM DbIO implementation for ISOCtry.

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
 *	CFSecRamISOCtryTable in-memory RAM DbIO implementation
 *	for ISOCtry.
 */
public class CFSecRamISOCtryTable
	implements ICFSecISOCtryTable
{
	private ICFSecSchema schema;
	private Map< CFSecISOCtryPKey,
				CFSecISOCtryBuff > dictByPKey
		= new HashMap< CFSecISOCtryPKey,
				CFSecISOCtryBuff >();
	private Map< CFSecISOCtryByISOCodeIdxKey,
			CFSecISOCtryBuff > dictByISOCodeIdx
		= new HashMap< CFSecISOCtryByISOCodeIdxKey,
			CFSecISOCtryBuff >();
	private Map< CFSecISOCtryByNameIdxKey,
			CFSecISOCtryBuff > dictByNameIdx
		= new HashMap< CFSecISOCtryByNameIdxKey,
			CFSecISOCtryBuff >();

	public CFSecRamISOCtryTable( ICFSecSchema argSchema ) {
		schema = argSchema;
	}

	public void createISOCtry( CFSecAuthorization Authorization,
		CFSecISOCtryBuff Buff )
	{
		final String S_ProcName = "createISOCtry";
		CFSecISOCtryPKey pkey = schema.getFactoryISOCtry().newPKey();
		pkey.setRequiredISOCtryId( schema.nextISOCtryIdGen() );
		Buff.setRequiredISOCtryId( pkey.getRequiredISOCtryId() );
		CFSecISOCtryByISOCodeIdxKey keyISOCodeIdx = schema.getFactoryISOCtry().newISOCodeIdxKey();
		keyISOCodeIdx.setRequiredISOCode( Buff.getRequiredISOCode() );

		CFSecISOCtryByNameIdxKey keyNameIdx = schema.getFactoryISOCtry().newNameIdxKey();
		keyNameIdx.setRequiredName( Buff.getRequiredName() );

		// Validate unique indexes

		if( dictByPKey.containsKey( pkey ) ) {
			throw new CFLibPrimaryKeyNotNewException( getClass(), S_ProcName, pkey );
		}

		if( dictByISOCodeIdx.containsKey( keyISOCodeIdx ) ) {
			throw new CFLibUniqueIndexViolationException( getClass(),
				S_ProcName,
				"ISOCtryCodeIdx",
				keyISOCodeIdx );
		}

		if( dictByNameIdx.containsKey( keyNameIdx ) ) {
			throw new CFLibUniqueIndexViolationException( getClass(),
				S_ProcName,
				"ISOCtryNameIdx",
				keyNameIdx );
		}

		// Validate foreign keys

		// Proceed with adding the new record

		dictByPKey.put( pkey, Buff );

		dictByISOCodeIdx.put( keyISOCodeIdx, Buff );

		dictByNameIdx.put( keyNameIdx, Buff );

	}

	public CFSecISOCtryBuff readDerived( CFSecAuthorization Authorization,
		CFSecISOCtryPKey PKey )
	{
		final String S_ProcName = "CFSecRamISOCtry.readDerived";
		CFSecISOCtryPKey key = schema.getFactoryISOCtry().newPKey();
		key.setRequiredISOCtryId( PKey.getRequiredISOCtryId() );
		CFSecISOCtryBuff buff;
		if( dictByPKey.containsKey( key ) ) {
			buff = dictByPKey.get( key );
		}
		else {
			buff = null;
		}
		return( buff );
	}

	public CFSecISOCtryBuff lockDerived( CFSecAuthorization Authorization,
		CFSecISOCtryPKey PKey )
	{
		final String S_ProcName = "CFSecRamISOCtry.readDerived";
		CFSecISOCtryPKey key = schema.getFactoryISOCtry().newPKey();
		key.setRequiredISOCtryId( PKey.getRequiredISOCtryId() );
		CFSecISOCtryBuff buff;
		if( dictByPKey.containsKey( key ) ) {
			buff = dictByPKey.get( key );
		}
		else {
			buff = null;
		}
		return( buff );
	}

	public CFSecISOCtryBuff[] readAllDerived( CFSecAuthorization Authorization ) {
		final String S_ProcName = "CFSecRamISOCtry.readAllDerived";
		CFSecISOCtryBuff[] retList = new CFSecISOCtryBuff[ dictByPKey.values().size() ];
		Iterator< CFSecISOCtryBuff > iter = dictByPKey.values().iterator();
		int idx = 0;
		while( iter.hasNext() ) {
			retList[ idx++ ] = iter.next();
		}
		return( retList );
	}

	public CFSecISOCtryBuff readDerivedByISOCodeIdx( CFSecAuthorization Authorization,
		String ISOCode )
	{
		final String S_ProcName = "CFSecRamISOCtry.readDerivedByISOCodeIdx";
		CFSecISOCtryByISOCodeIdxKey key = schema.getFactoryISOCtry().newISOCodeIdxKey();
		key.setRequiredISOCode( ISOCode );

		CFSecISOCtryBuff buff;
		if( dictByISOCodeIdx.containsKey( key ) ) {
			buff = dictByISOCodeIdx.get( key );
		}
		else {
			buff = null;
		}
		return( buff );
	}

	public CFSecISOCtryBuff readDerivedByNameIdx( CFSecAuthorization Authorization,
		String Name )
	{
		final String S_ProcName = "CFSecRamISOCtry.readDerivedByNameIdx";
		CFSecISOCtryByNameIdxKey key = schema.getFactoryISOCtry().newNameIdxKey();
		key.setRequiredName( Name );

		CFSecISOCtryBuff buff;
		if( dictByNameIdx.containsKey( key ) ) {
			buff = dictByNameIdx.get( key );
		}
		else {
			buff = null;
		}
		return( buff );
	}

	public CFSecISOCtryBuff readDerivedByIdIdx( CFSecAuthorization Authorization,
		short ISOCtryId )
	{
		final String S_ProcName = "CFSecRamISOCtry.readDerivedByIdIdx() ";
		CFSecISOCtryPKey key = schema.getFactoryISOCtry().newPKey();
		key.setRequiredISOCtryId( ISOCtryId );

		CFSecISOCtryBuff buff;
		if( dictByPKey.containsKey( key ) ) {
			buff = dictByPKey.get( key );
		}
		else {
			buff = null;
		}
		return( buff );
	}

	public CFSecISOCtryBuff readBuff( CFSecAuthorization Authorization,
		CFSecISOCtryPKey PKey )
	{
		final String S_ProcName = "CFSecRamISOCtry.readBuff";
		CFSecISOCtryBuff buff = readDerived( Authorization, PKey );
		if( ( buff != null ) && ( ! buff.getClassCode().equals( "a004" ) ) ) {
			buff = null;
		}
		return( buff );
	}

	public CFSecISOCtryBuff lockBuff( CFSecAuthorization Authorization,
		CFSecISOCtryPKey PKey )
	{
		final String S_ProcName = "lockBuff";
		CFSecISOCtryBuff buff = readDerived( Authorization, PKey );
		if( ( buff != null ) && ( ! buff.getClassCode().equals( "a004" ) ) ) {
			buff = null;
		}
		return( buff );
	}

	public CFSecISOCtryBuff[] readAllBuff( CFSecAuthorization Authorization )
	{
		final String S_ProcName = "CFSecRamISOCtry.readAllBuff";
		CFSecISOCtryBuff buff;
		ArrayList<CFSecISOCtryBuff> filteredList = new ArrayList<CFSecISOCtryBuff>();
		CFSecISOCtryBuff[] buffList = readAllDerived( Authorization );
		for( int idx = 0; idx < buffList.length; idx ++ ) {
			buff = buffList[idx];
			if( ( buff != null ) && buff.getClassCode().equals( "a004" ) ) {
				filteredList.add( buff );
			}
		}
		return( filteredList.toArray( new CFSecISOCtryBuff[0] ) );
	}

	public CFSecISOCtryBuff readBuffByIdIdx( CFSecAuthorization Authorization,
		short ISOCtryId )
	{
		final String S_ProcName = "CFSecRamISOCtry.readBuffByIdIdx() ";
		CFSecISOCtryBuff buff = readDerivedByIdIdx( Authorization,
			ISOCtryId );
		if( ( buff != null ) && buff.getClassCode().equals( "a004" ) ) {
			return( (CFSecISOCtryBuff)buff );
		}
		else {
			return( null );
		}
	}

	public CFSecISOCtryBuff readBuffByISOCodeIdx( CFSecAuthorization Authorization,
		String ISOCode )
	{
		final String S_ProcName = "CFSecRamISOCtry.readBuffByISOCodeIdx() ";
		CFSecISOCtryBuff buff = readDerivedByISOCodeIdx( Authorization,
			ISOCode );
		if( ( buff != null ) && buff.getClassCode().equals( "a004" ) ) {
			return( (CFSecISOCtryBuff)buff );
		}
		else {
			return( null );
		}
	}

	public CFSecISOCtryBuff readBuffByNameIdx( CFSecAuthorization Authorization,
		String Name )
	{
		final String S_ProcName = "CFSecRamISOCtry.readBuffByNameIdx() ";
		CFSecISOCtryBuff buff = readDerivedByNameIdx( Authorization,
			Name );
		if( ( buff != null ) && buff.getClassCode().equals( "a004" ) ) {
			return( (CFSecISOCtryBuff)buff );
		}
		else {
			return( null );
		}
	}

	public void updateISOCtry( CFSecAuthorization Authorization,
		CFSecISOCtryBuff Buff )
	{
		CFSecISOCtryPKey pkey = schema.getFactoryISOCtry().newPKey();
		pkey.setRequiredISOCtryId( Buff.getRequiredISOCtryId() );
		CFSecISOCtryBuff existing = dictByPKey.get( pkey );
		if( existing == null ) {
			throw new CFLibStaleCacheDetectedException( getClass(),
				"updateISOCtry",
				"Existing record not found",
				"ISOCtry",
				pkey );
		}
		if( existing.getRequiredRevision() != Buff.getRequiredRevision() ) {
			throw new CFLibCollisionDetectedException( getClass(),
				"updateISOCtry",
				pkey );
		}
		Buff.setRequiredRevision( Buff.getRequiredRevision() + 1 );
		CFSecISOCtryByISOCodeIdxKey existingKeyISOCodeIdx = schema.getFactoryISOCtry().newISOCodeIdxKey();
		existingKeyISOCodeIdx.setRequiredISOCode( existing.getRequiredISOCode() );

		CFSecISOCtryByISOCodeIdxKey newKeyISOCodeIdx = schema.getFactoryISOCtry().newISOCodeIdxKey();
		newKeyISOCodeIdx.setRequiredISOCode( Buff.getRequiredISOCode() );

		CFSecISOCtryByNameIdxKey existingKeyNameIdx = schema.getFactoryISOCtry().newNameIdxKey();
		existingKeyNameIdx.setRequiredName( existing.getRequiredName() );

		CFSecISOCtryByNameIdxKey newKeyNameIdx = schema.getFactoryISOCtry().newNameIdxKey();
		newKeyNameIdx.setRequiredName( Buff.getRequiredName() );

		// Check unique indexes

		if( ! existingKeyISOCodeIdx.equals( newKeyISOCodeIdx ) ) {
			if( dictByISOCodeIdx.containsKey( newKeyISOCodeIdx ) ) {
				throw new CFLibUniqueIndexViolationException( getClass(),
					"updateISOCtry",
					"ISOCtryCodeIdx",
					newKeyISOCodeIdx );
			}
		}

		if( ! existingKeyNameIdx.equals( newKeyNameIdx ) ) {
			if( dictByNameIdx.containsKey( newKeyNameIdx ) ) {
				throw new CFLibUniqueIndexViolationException( getClass(),
					"updateISOCtry",
					"ISOCtryNameIdx",
					newKeyNameIdx );
			}
		}

		// Validate foreign keys

		// Update is valid

		Map< CFSecISOCtryPKey, CFSecISOCtryBuff > subdict;

		dictByPKey.remove( pkey );
		dictByPKey.put( pkey, Buff );

		dictByISOCodeIdx.remove( existingKeyISOCodeIdx );
		dictByISOCodeIdx.put( newKeyISOCodeIdx, Buff );

		dictByNameIdx.remove( existingKeyNameIdx );
		dictByNameIdx.put( newKeyNameIdx, Buff );

	}

	public void deleteISOCtry( CFSecAuthorization Authorization,
		CFSecISOCtryBuff Buff )
	{
		final String S_ProcName = "CFSecRamISOCtryTable.deleteISOCtry() ";
		String classCode;
		CFSecISOCtryPKey pkey = schema.getFactoryISOCtry().newPKey();
		pkey.setRequiredISOCtryId( Buff.getRequiredISOCtryId() );
		CFSecISOCtryBuff existing = dictByPKey.get( pkey );
		if( existing == null ) {
			return;
		}
		if( existing.getRequiredRevision() != Buff.getRequiredRevision() )
		{
			throw new CFLibCollisionDetectedException( getClass(),
				"deleteISOCtry",
				pkey );
		}
					schema.getTableISOCtryLang().deleteISOCtryLangByCtryIdx( Authorization,
						existing.getRequiredISOCtryId() );
					schema.getTableISOCtryCcy().deleteISOCtryCcyByCtryIdx( Authorization,
						existing.getRequiredISOCtryId() );
		CFSecISOCtryByISOCodeIdxKey keyISOCodeIdx = schema.getFactoryISOCtry().newISOCodeIdxKey();
		keyISOCodeIdx.setRequiredISOCode( existing.getRequiredISOCode() );

		CFSecISOCtryByNameIdxKey keyNameIdx = schema.getFactoryISOCtry().newNameIdxKey();
		keyNameIdx.setRequiredName( existing.getRequiredName() );

		// Validate reverse foreign keys

		// Delete is valid
		Map< CFSecISOCtryPKey, CFSecISOCtryBuff > subdict;

		dictByPKey.remove( pkey );

		dictByISOCodeIdx.remove( keyISOCodeIdx );

		dictByNameIdx.remove( keyNameIdx );

	}
	public void deleteISOCtryByIdIdx( CFSecAuthorization Authorization,
		short argISOCtryId )
	{
		CFSecISOCtryPKey key = schema.getFactoryISOCtry().newPKey();
		key.setRequiredISOCtryId( argISOCtryId );
		deleteISOCtryByIdIdx( Authorization, key );
	}

	public void deleteISOCtryByIdIdx( CFSecAuthorization Authorization,
		CFSecISOCtryPKey argKey )
	{
		boolean anyNotNull = false;
		anyNotNull = true;
		if( ! anyNotNull ) {
			return;
		}
		CFSecISOCtryBuff cur;
		LinkedList<CFSecISOCtryBuff> matchSet = new LinkedList<CFSecISOCtryBuff>();
		Iterator<CFSecISOCtryBuff> values = dictByPKey.values().iterator();
		while( values.hasNext() ) {
			cur = values.next();
			if( argKey.equals( cur ) ) {
				matchSet.add( cur );
			}
		}
		Iterator<CFSecISOCtryBuff> iterMatch = matchSet.iterator();
		while( iterMatch.hasNext() ) {
			cur = iterMatch.next();
			cur = schema.getTableISOCtry().readDerivedByIdIdx( Authorization,
				cur.getRequiredISOCtryId() );
			deleteISOCtry( Authorization, cur );
		}
	}

	public void deleteISOCtryByISOCodeIdx( CFSecAuthorization Authorization,
		String argISOCode )
	{
		CFSecISOCtryByISOCodeIdxKey key = schema.getFactoryISOCtry().newISOCodeIdxKey();
		key.setRequiredISOCode( argISOCode );
		deleteISOCtryByISOCodeIdx( Authorization, key );
	}

	public void deleteISOCtryByISOCodeIdx( CFSecAuthorization Authorization,
		CFSecISOCtryByISOCodeIdxKey argKey )
	{
		CFSecISOCtryBuff cur;
		boolean anyNotNull = false;
		anyNotNull = true;
		if( ! anyNotNull ) {
			return;
		}
		LinkedList<CFSecISOCtryBuff> matchSet = new LinkedList<CFSecISOCtryBuff>();
		Iterator<CFSecISOCtryBuff> values = dictByPKey.values().iterator();
		while( values.hasNext() ) {
			cur = values.next();
			if( argKey.equals( cur ) ) {
				matchSet.add( cur );
			}
		}
		Iterator<CFSecISOCtryBuff> iterMatch = matchSet.iterator();
		while( iterMatch.hasNext() ) {
			cur = iterMatch.next();
			cur = schema.getTableISOCtry().readDerivedByIdIdx( Authorization,
				cur.getRequiredISOCtryId() );
			deleteISOCtry( Authorization, cur );
		}
	}

	public void deleteISOCtryByNameIdx( CFSecAuthorization Authorization,
		String argName )
	{
		CFSecISOCtryByNameIdxKey key = schema.getFactoryISOCtry().newNameIdxKey();
		key.setRequiredName( argName );
		deleteISOCtryByNameIdx( Authorization, key );
	}

	public void deleteISOCtryByNameIdx( CFSecAuthorization Authorization,
		CFSecISOCtryByNameIdxKey argKey )
	{
		CFSecISOCtryBuff cur;
		boolean anyNotNull = false;
		anyNotNull = true;
		if( ! anyNotNull ) {
			return;
		}
		LinkedList<CFSecISOCtryBuff> matchSet = new LinkedList<CFSecISOCtryBuff>();
		Iterator<CFSecISOCtryBuff> values = dictByPKey.values().iterator();
		while( values.hasNext() ) {
			cur = values.next();
			if( argKey.equals( cur ) ) {
				matchSet.add( cur );
			}
		}
		Iterator<CFSecISOCtryBuff> iterMatch = matchSet.iterator();
		while( iterMatch.hasNext() ) {
			cur = iterMatch.next();
			cur = schema.getTableISOCtry().readDerivedByIdIdx( Authorization,
				cur.getRequiredISOCtryId() );
			deleteISOCtry( Authorization, cur );
		}
	}
}
